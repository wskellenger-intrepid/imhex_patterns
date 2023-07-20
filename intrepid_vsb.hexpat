#pragma endian little
#pragma pattern_limit 50000000  //up to 5M iterations
#pragma array_limit 10000000  //up to 1M itterations

#include <type/magic.pat>
#include <type/types/c.pat>
#include <std/mem.pat>

#define icsSpyMessageVSB_SIZE 64

enum eicsspyenumProtocol : u8
{
	icsspyProtocolCustom = 0,
	icsspyProtocolCAN = 1,
	icsspyProtocolGMLAN = 2,
	icsspyProtocolJ1850VPW = 3,
	icsspyProtocolJ1850PWM = 4,
	icsspyProtocolISO9141 = 5,
	icsspyProtocolKeyword2000 = 6,
	icsspyProtocolGM_ALDL_UART = 7,
	icsspyProtocolCHRYSLER_CCD = 8,
	icsspyProtocolCHRYSLER_SCI = 9,
	icsspyProtocolFORD_UBP = 10,
	icsspyProtocolBEAN = 11,
	icsspyProtocolLIN = 12,
	icsspyProtocolJ1708 = 13,
	icsspyProtocolCHRYSLER_JVPW = 14,
	icsspyProtocolJ1939 = 15,
	icsspyProtocolFlexRay = 16,
	icsspyProtocolMOST = 17,
	icsspyProtocolCGI = 18,
	icsspyProtocolGME_CIM_SCL_Kline = 19,
	icsspyProtocolSPI = 20,
	icsspyProtocolI2C = 21,
	icsspyProtocolGenericUART = 22,
	icsspyProtocolJTAG = 23,
	icsspyProtocolUNIO = 24,
	icsspyProtocolDALLAS_1WIRE = 25,
	icsspyProtocolGenericManchester = 26,
	icsspyProtocolSent = 27,
	icsspyProtocolUart = 28,
	icsspyProtocolEthernet = 29,
	icsspyProtocolCanFD = 30,
	icsspyProtocolGMFSA = 31,
	icsspyProtocolTCP = 32,
	icsspyProtocolUDP = 33,
	icsspyProtocolAutosar = 34,
	icsspyProtocolA2B = 35,
	icsspyProtocolwBMS = 36,
};


enum TimeStampHardwareID : u8
{
	HARDWARE_TIMESTAMP_ID_NONE = 0,
	HARDWARE_TIMESTAMP_ID_VSI,
	HARDWARE_TIMESTAMP_ID_AVT_716,
	HARDWARE_TIMESTAMP_ID_NI_CAN,
	HARDWARE_TIMESTAMP_ID_NEOVI,
	HARDWARE_TIMESTAMP_ID_AVT_717,
	HARDWARE_TIMESTAMP_ID_NEOv6_VCAN,
	HARDWARE_TIMESTAMP_ID_DOUBLE_SEC,
	HARDWARE_TIMESTAMP_ID_NEORED_10US,
	HARDWARE_TIMESTAMP_ID_NEORED_25NS,
	HARDWARE_TIMESTAMP_ID_NEORED_10NS,
};

enum TimeStampSystemID : u8
{
	SYSTEM_TIMESTAMP_ID_NONE = 0,
	SYSTEM_TIMESTAMP_ID_TIMEGETTIME_API,
};

struct VSBSpyMessage
{
	uint32_t StatusBitField;
	uint32_t StatusBitField2;
	uint32_t TimeHardware;
	uint32_t TimeHardware2;
	uint32_t TimeSystem;
	uint32_t TimeSystem2;
	TimeStampHardwareID TimeStampHardwareID;
	TimeStampSystemID TimeStampSystemID;
	uint8_t NetworkID;
	uint8_t NodeID;
	eicsspyenumProtocol Protocol;
	uint8_t MessagePieceID;
	bool ExtraDataPtrEnabled;
	uint8_t NumberBytesHeader;
	uint8_t NumberBytesData;
	uint8_t NetworkID2;
	int16_t DescriptionID;
	uint32_t ArbIDOrHeader;
	uint8_t Data[8];
	uint8_t AckBytes[8];
	uint32_t ExtraDataPtr;
	uint8_t MiscData;
	uint8_t Reserved[3];
} [[format("VSBSpyMessage_format")]];

fn VSBSpyMessage_format(VSBSpyMessage msg)
{
	uint64_t hwtimestamp = 0;
	hwtimestamp = msg.TimeHardware2<<32;
	hwtimestamp |= msg.TimeHardware;

	uint64_t systemtimestamp = 0;
	systemtimestamp = msg.TimeSystem2<<32;
	systemtimestamp |= msg.TimeSystem;

	return std::format("hwTimestamp: {:X}  sysTimeStamp: {:X}", hwtimestamp, systemtimestamp);
}; 

struct VsbFileHeader {
    type::Magic<"icsbin"> id;
	uint32_t file_version;
};

struct VsbVersion104Message
{
    VSBSpyMessage msg;
    uint8_t data[msg.ExtraDataPtr];
};

//struct VsbFile 
//    VsbFileHeader file_header;
//    if (file_header.file_version == 0x104)
//    {
//        VsbVersion104Message messages[while (!std::mem::eof())];
//    }
//};

VsbFileHeader file_header @ 0x00;
VsbVersion104Message messages[while($ < std::mem::size())] @ $;