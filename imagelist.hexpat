// Embarcadero ImageList dissection
// William Skellenger <wskellenger@intrepidcs.com>
// MIT License

//WIP

#include <type/types/c.pat>

struct ImageList {
    uint8_t magic[2];
    uint8_t unk;
    uint8_t unk2;
    uint16_t images;
    uint16_t unk3;
    uint16_t opts;
    uint16_t unk5;
    uint16_t unk6;  
};

//stretch is opts 0xc0 00 crop is 0xcc 00, center ix d800

ImageList il @ 0x00;
