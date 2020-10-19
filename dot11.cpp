#include "dot11.h"

uint8_t * dot11_data_frame::get_BSSID(void)
{
    uint8_t status = this->fc.flags & (dot11_fc::flags::TO_DS | dot11_fc::flags::FROM_DS);
    switch(status)
    {
    case 0b10:  //DBS
        return this->addr2;
        break;
    case 0b01:  //BSD
        return this->addr1;
        break;
    case 0b00:  //DSB
        return this->addr3;
        break;
    case 0b11:  //RTDS
        printf("i don't know\n");
        return nullptr;
        break;
    default:
        return nullptr;
    }
}

uint8_t * dot11_mgt_frame::get_BSSID(void)
{
    uint8_t status = this->fc.flags & (dot11_fc::flags::TO_DS | dot11_fc::flags::FROM_DS);
    switch(status)
    {
    case 0b10:  //DBS
        return this->addr2;
        break;
    case 0b01:  //BSD
        return this->addr1;
        break;
    case 0b00:  //DSB
        return this->addr3;
        break;
    case 0b11:  //RTDS
        printf("i don't know\n");
        return nullptr;
        break;
    default:
        return nullptr;
    }
}

uint8_t * dot11_mgt_frame::get_tag(uint8_t tag, int tags_len)
{
    uint8_t * offset = (uint8_t *)this + sizeof(dot11_frame);

    uint8_t * start_offset = offset;

    while(((*offset) != tag) && (offset - start_offset < tags_len))
    {
        offset += (*(offset + 1)) + 2;
    }

    return offset;
}

uint8_t * dot11_beacon_frame::get_tag(uint8_t tag, int tags_len)
{
    uint8_t * offset = (uint8_t *)this + sizeof(dot11_beacon_frame);

    uint8_t * start_offset = offset;

    while(((*offset) != tag) && (offset - start_offset < tags_len))
    {
        offset += (*(offset + 1)) + 2;
    }

    return offset;

}

void ap_info::Print(void)
{

    std::cout << BSSID << "\t";
    printf("-%d\t", (~(antsignal) & 0xFF) + 0b1);
    printf("%d\t", cnt);
    printf("%d\t", channel);
    printf("%s\n", ESSID.c_str());
//    cout << ESSID << "\t";
    printf("\n");
}

std::string ap_info::String(void)
{
    std::string temp;

    temp = "1\t" + ESSID + "\t" + BSSID + "\t" + std::to_string(channel);

    return temp;
}


void station_info::Print(void)
{

    std::cout << BSSID << "\t" << STATION << "\t";
    printf("-%d\t", (~(antsignal) & 0xFF) + 0b1);
    printf("%d\t", cnt);
    std::cout << probe << "\t";
    printf("\n");
}

void data_station_info::Print(void)
{

    std::cout << BSSID << "\t" << STATION << "\t";
    printf("-%d\t", (~(antsignal) & 0xFF) + 0b1);
    printf("\n");
}

std::string data_station_info::String(void)
{
    std::string temp;
    char temp_antsignal[20]={0};

    sprintf(temp_antsignal,"-%d\t", (~(antsignal) & 0xFF) + 0b1);

    temp = "2\t" + BSSID + "\t" + STATION + "\t" + temp_antsignal;

    return temp;

}


uint8_t* set_deauth(uint8_t * target, uint8_t * addr)
{


    uint8_t * packet = (uint8_t *)malloc(sizeof(radiotap_header) + sizeof(dot11_mgt_frame) + 2);
    radiotap_header * rt_header = (radiotap_header *)packet;
    rt_header->it_version = 0;
    rt_header->it_pad = 0;
    rt_header->it_len = 8;
    rt_header->it_present = 0;

    dot11_mgt_frame * frame = (dot11_mgt_frame *)(packet + rt_header->it_len);
    frame->fc.version = 0;
    frame->fc.type = dot11_fc::type::MANAGEMENT;
    frame->fc.subtype = dot11_fc::subtype::DEAUTH;
    frame->fc.flags = 0;
    memcpy(frame->addr1, target, 6);
    memcpy(frame->addr2, addr, 6);
    memcpy(frame->addr3, addr, 6);
    frame->frag_num = 0;
    frame->seq_num = 0;

    *(packet+sizeof(radiotap_header) + sizeof(dot11_mgt_frame)) = (uint16_t)(0x0007); // Class 3 frame received from nonassociated STA

    return (uint8_t*)packet;
}

uint8_t* set_beacon(uint8_t * addr)
{

    uint8_t * packet = (uint8_t *)malloc(sizeof(radiotap_header) + sizeof(dot11_mgt_frame) + 2);
    radiotap_header * rt_header = (radiotap_header *)packet;
    rt_header->it_version = 0;
    rt_header->it_pad = 0;
    rt_header->it_len = 8;

    dot11_beacon_frame * frame = (dot11_beacon_frame *)(packet + rt_header->it_len);
    frame->fc.type = dot11_fc::type::MANAGEMENT;
    frame->fc.subtype = dot11_fc::subtype::BEACON;
    memset(frame->addr1, 0xFF, 6);
    memcpy(frame->addr2, addr, 6);
    memcpy(frame->addr3, addr, 6);
    frame->frag_num = 0;
    frame->seq_num = 0;

    return (uint8_t*)packet;
}

std::string mac_to_string(uint8_t * addr)
{
    char temp[18];
    sprintf(temp, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return std::string(temp);

}

uint8_t * string_to_mac(uint8_t * addr)
{
    uint8_t temp[6] = {0};
    sscanf((char*)addr, "%02x:%02x:%02x:%02x:%02x:%02x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]);

    return temp;
}

bool check_dev(char *dev)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
        return false;

    return true;
}

bool send_data(int client_sock, char *data)
{
    char result[BUF_SIZE] = {0};
    size_t data_length = strlen(data);
    result[0] = (data_length >> 8) & 0xFF;
    result[1] = data_length & 0xFF;
    memcpy(result + 2, data, strlen(data));

    if (write(client_sock, result, strlen(data) + 2) <= 0)
    {
        return false;
    }
    return true;
}

bool recv_data(int client_sock, char *data)
{
    unsigned char buf[BUF_SIZE] = {0};
    char result[BUF_SIZE] = {0};
    size_t data_length = 0;

    if (read(client_sock, buf, 2) < 0)
    {
        return false;
    }

    data_length = (buf[0] << 8) + buf[1];

    if (read(client_sock, result, data_length) <= 0)
    {
        return false;
    }

    result[data_length] = '\0';

    memcpy(data, result, sizeof(result));

    return true;
}

