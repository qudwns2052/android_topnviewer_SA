#include "include.h"

typedef struct station_map_info
{
    std::string ap;
    std::string signal;
}station_map_info;

static std::map<Mac, station_map_info> station_map;

pcap_t *handle;
char dev[BUF_SIZE] = {0};
char errbuf[PCAP_ERRBUF_SIZE];

int client_sock;
int server_sock;
bool ap_active;
bool hopping_active;


void hopping_func()
{

    int channel_list[15] = {1, 7, 2, 8, 3, 9, 4, 10, 5, 11, 6, 36, 44, 40, 48};
    //    int channel_list[20] = {1, 7, 2, 8, 3, 9, 4, 10, 5, 11, 6, 36, 44, 40, 48, 149, 157, 165, 153, 161};

    std::string system_string;

    while (true)
    {
        for (int i = 0; i < 15; i++)
        {
            if(hopping_active)
            {
            system_string = "iwconfig wlan0 channel " + std::to_string(channel_list[i]);
            std::cout << system_string << std::endl;
            system(system_string.c_str());
            usleep(100000);
            }
        }
    
    }
}

void get_ap()
{
    while (ap_active)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        radiotap_header *rt_header = (radiotap_header *)(packet);
        dot11_mgt_frame *frame = (dot11_mgt_frame *)(packet + rt_header->it_len);

        if ((frame->fc.type == dot11_fc::type::CONTROL))
        {
            continue;
        }

        //        printf("capture !\n");

        //get station info
        if ((frame->fc.type == dot11_fc::type::DATA) && (frame->fc.subtype == dot11_fc::subtype::_NO_DATA))
        {
            dot11_data_frame *data_frame = (dot11_data_frame *)(packet + rt_header->it_len);
            uint8_t selected_ap[6] = {0};

            memcpy(selected_ap, data_frame->get_BSSID(), 6);

            Mac BSSID = selected_ap;
            Mac STATION = data_frame->addr2;
            uint8_t antsignal = *rt_header->radiotap_present_flag(DBM_ANTSIGNAL);


            data_station_info d_s_info;
            d_s_info.BSSID = BSSID;
            d_s_info.STATION = STATION;
            d_s_info.antsignal = antsignal;
            d_s_info.isAttack = false;

            if(station_map.find(STATION) != station_map.end())
            {
                if(station_map[STATION].signal == std::to_string(antsignal))
                {
                    continue;
                }
            }

            station_map[STATION].signal = std::to_string(d_s_info.antsignal);
            station_map[STATION].ap = BSSID;
            std::string buf_string;
            char data[BUF_SIZE] = {0};
            buf_string = d_s_info.String();
            memcpy(data, buf_string.c_str(), BUF_SIZE);
            send_data(client_sock, data);
            printf("send Station info %s\n", data);
            usleep(100000);

        }

        // AP
        if ((frame->fc.subtype == dot11_fc::subtype::BEACON) || (frame->fc.subtype == dot11_fc::subtype::PROBE_RES))
        {
            dot11_beacon_frame *beacon_frame = (dot11_beacon_frame *)(frame);
            int dot11_tags_len = header->len - (rt_header->it_len + sizeof(dot11_beacon_frame));

            Mac BSSID = frame->get_BSSID(); //key
            uint8_t antsignal = *rt_header->radiotap_present_flag(DBM_ANTSIGNAL);
            uint8_t channel = *((dot11_tagged_param *)beacon_frame->get_tag(3, dot11_tags_len))->get_data();
            //cnt
            std::string ESSID = ((dot11_tagged_param *)beacon_frame->get_tag(0, dot11_tags_len))->get_ssid();

            ap_info temp_ap_info;
            temp_ap_info.BSSID = BSSID;
            temp_ap_info.antsignal = antsignal;
            temp_ap_info.channel = channel;
            temp_ap_info.ESSID = ESSID;

            // if (ap_map.find(BSSID) == ap_map.end())
            // {
            //     temp_ap_info.cnt = 1;
            //     ap_map[BSSID].channel = channel;

            //     std::string buf_string;
            //     char data[BUF_SIZE] = {0};

            //     buf_string = temp_ap_info.String();
            //     // buf_string = "1\t" + ESSID + "\t" + BSSID;

            //     memcpy(data, buf_string.c_str(), BUF_SIZE);

            //     if (strlen(data) > 18)
            //         send_data(client_sock, data);

            //     //                printf("send AP info %s\n", data);

            //     usleep(100000);
            // }

            // send TIM.aid
            if (frame->fc.subtype == dot11_fc::subtype::BEACON)
            {

                if (*(beacon_frame->get_tag(5, dot11_tags_len) + 5) == 0)
                {
                    memset(beacon_frame->get_tag(5, dot11_tags_len) + 5, 0xFF, 1);
                    beacon_frame->seq_num += 0b1;

                    usleep(5000); // 9000 10 2000
                    for (int i = 0; i < 20; i++)
                    {
                        if (pcap_sendpacket(handle, packet, header->caplen) != 0)
                        {
                            printf("error\n");
                        }
                        usleep(1000);
                    }
                }
            }
        }
    }
}


// void send_deauth(char *read_data)
// {
//     char data[BUF_SIZE] = {0};

//     memcpy(data, read_data, BUF_SIZE);

//     printf("data = %s\n", data);

//     char *ptr = strtok(data, "\t");

//     uint8_t selected_ap[6] = {0};
//     uint8_t selected_station[6] = {0};

//     memcpy(selected_ap, string_to_mac((uint8_t *)ptr), 6);

//     std::cout << "selected ap = " << mac_to_string(selected_ap) << std::endl;

//     ptr = strtok(NULL, "\t");

//     memcpy(selected_station, string_to_mac((uint8_t *)ptr), 6);

//     std::cout << "selected station = " << mac_to_string(selected_station) << std::endl;

//     if (mac_to_string(selected_station) == "ff:ff:ff:ff:ff:ff")
//     {
//         if (ap_map_broadcast[selected_ap] == true)
//         {
//             printf("BSSID = ff:ff:ff:ff:ff:ff deauth stop\n");
//             ap_map_broadcast[selected_ap] = false;
//         }
//         else
//         {
//             ap_map_broadcast[selected_ap] = true;
//             printf("BSSID = ff:ff:ff:ff:ff:ff deauth start\n");

//             Mac key = selected_ap;
//             int channel = ap_map[selected_ap].channel;
//             printf("channel = %d\n", ap_map[selected_ap].channel);

//             uint8_t *deauth_frame = set_deauth(selected_station, selected_ap);
//             std::thread t = std::thread(t_func_broadcast, (uint8_t *)deauth_frame, channel, key);
//             t.detach();
//         }

//         return;
//     }

//     for (auto it = ap_map[selected_ap].map_station.begin(); it != ap_map[selected_ap].map_station.end(); it++)
//     {
//         if (mac_to_string(selected_station) == it->second.STATION)
//         {
//             if (it->second.isAttack == true)
//             {
//                 printf("BSSID = %s deauth stop\n", it->second.STATION.c_str());
//                 it->second.isAttack = false;
//             }
//             else
//             {
//                 it->second.isAttack = true;
//                 printf("BSSID = %s deauth start\n", it->second.STATION.c_str());
//                 // printf("it first = %s\n", it->first);
//                 //                Mac selected_station = it->first;
//                 // std::thread t = std::thread(t_func, selected_ap, selected_station);
//                 // t.detach();

//                 Mac key1 = selected_ap;
//                 Mac key2 = selected_station;
//                 int channel = ap_map[selected_ap].channel;
//                 printf("channel = %d\n", ap_map[selected_ap].channel);

//                 uint8_t *deauth_frame = set_deauth(selected_station, selected_ap);
//                 std::thread t = std::thread(t_func, (uint8_t *)deauth_frame, channel, key1, key2);
//                 t.detach();
//             }

//             break;
//         }
//     }
// }

int main(int argc, char *argv[])
{
    int server_port = 9998;

    //socket connection
    {
        if ((server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            printf("socket create error\n");
            return -1;
        }

        int option = 1;
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
        {
            printf("socket option set error\n");
            return -1;
        }

        struct sockaddr_in server_addr, client_addr;
        memset(&server_addr, 0x00, sizeof(server_addr));
        memset(&client_addr, 0x00, sizeof(client_addr));
        int client_addr_size = sizeof(client_addr);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);

        if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            printf("bind error\n");
            return -1;
        }

        if (listen(server_sock, 5) < 0)
        {
            printf("listen error\n");
            return -1;
        }

        if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_size)) < 0)
        {
            printf("accept error\n");
        }

        printf("connection ok\n");
    }

    //pcap open
    {
        memcpy(dev, "wlan0", 5);
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

        if (handle == NULL)
        {
            printf("fail open_offline...%s\n", errbuf);
            return -1;
        }
    }

    //switch
    {
        char buf[BUF_SIZE] = {0};
        char data[BUF_SIZE] = {0};

        //channel hopping
        hopping_active = false;
        std::thread t = std::thread(hopping_func);
        t.detach();

        while (true)
        {
            memset(buf, 0x00, BUF_SIZE);
            recv_data(client_sock, buf);

            memset(data, 0x00, BUF_SIZE);
            printf("command = %s\n", buf);

            if (!memcmp(buf, "1", 1)) // scan start
            {
                ap_active = true;
                hopping_active = true;
                std::thread t = std::thread(get_ap);
                t.detach();
            }
            else if (!memcmp(buf, "5", 1)) // scan stop
            {
                ap_active = false;
                hopping_active = false;
            }
            else
            {
                printf("switch error\n");
                break;
            }

            // else if (!memcmp(buf, "2", 1)) // station scan start
            // {
            //     station_active = true;
            //     recv_data(client_sock, data);
            //     std::thread t = std::thread(get_station, data);
            //     t.detach();
            // }
            // else if (!memcmp(buf, "6", 1)) // station scan stop
            // {
            //     station_active = false;
            // }
        }
    }

    // send all device && get dev
    {
        //        pcap_if_t *all;
        //        pcap_if_t *temp;
        //        char data[BUF_SIZE] = {0};

        //        if (pcap_findalldevs(&all, errbuf) == -1)
        //        {
        //            printf("error in pcap_findalldevs(%s)\n", errbuf);
        //            return -1;
        //        }

        //        memset(data, 0x00, sizeof(data));

        //        for (temp = all; temp; temp = temp->next)
        //        {
        //            if (check_dev(temp->name))
        //            {
        //                strcat(temp->name, ",");
        //                strcat(data, temp->name);
        //            }
        //        }

        //        if (write(client_sock, data, sizeof(data)) <= 0)
        //        {
        //            printf("write error\n");
        //            return -1;
        //        }

        //        printf("write dev list ok\n");

        //        if (read(client_sock, dev, BUF_SIZE) <= 0)
        //        {
        //            printf("read error\n");
        //            return -1;
        //        }

        //        printf("dev = %s\n", dev);
    }

    pcap_close(handle);

    return 0;
}
