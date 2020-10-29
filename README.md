# RaziCTF 2020

I almost got no time working on this CTF, but in the end became a tiebreaker to actually win the CTF...

### Long Battery Life

_Really long battery life and very durable! Hint: USB traffic from Wireless Mouse_

We got a PCAP file, filled with USB packet captures. Opened it in Wireshark, saw several configuration about some Video Capture Device and 2.4G Keyboard Mouse.

So the hint wasn't there in the first place, so we went down the rabbit hole, we thought that the first several capture was from video capture device, because the configuration section told something about video encoding. And apparently it wasn't. We also thought that it could be keyboard, because of the 8 byte data instead of the mouse's 4 bytes stream (at least from what I read from USB documentation). But if it's keyboard it doesn't make any sense, it can't be parsed as an actual readable string.

![The rabbithole TM](https://github.com/spitfirerxf/RaziCTF-2020/raw/main/rabbithole.png)

And the hint came out (because only 1 people solved it without the hint), and we immediately worked on it. We found [this wiki](https://ctf-wiki.github.io/ctf-wiki/misc/traffic/protocols/USB/) about USB, and explaining that mouse can actually be 8 bytes. So we went to [this repo](https://github.com/WangYihang/UsbMiceDataHacker) and modify it a bit so it can parse our mouse capture and draw it to matplotlib.

Then save it into a file and we got the flag.

![The Flag](https://github.com/spitfirerxf/RaziCTF-2020/raw/main/out.png)

`RaziCTF{I_Love_My_Mouse}`

### Industrial Network

_In an industrial Modbus RTU network based on RS485 bus, the master wants to read a sensor data, the data packet has been sent to the slave is like below. Send the slave response to the master, also imagine the slave data is 40 (decimal). (data is in Hex format) Master req. = 06 03 00 00 00 01 85 BD The answer is not in the regular flag format._

So let's parse the master's request according to [this Modbus documentation](https://www.modbustools.com/modbus.html):
```
06 03 00 00 00 01 85 BD 
06 is the slave number
03 is the function, and here it's Read Holding Register
00 00 is the register number offset, 00 00 is counting from register 0
00 01 is the number of register read, incrementally from the offset
85 BD is the two CRC
```

So basically it's just asking for register value in slave number 06. Now we can expect the slave's answer:

```
06 03 02 00 28 0D 9A
06 is slave number
03 function
02 is the byte, per register holding 2 bytes
00 28 is the actual data, 40 in decimal
0D 9A is two CRC
```

Then how's the CRC calculated? We found a [simple C script](https://ctlsys.com/support/how_to_compute_the_modbus_rtu_message_crc/) to calculate it for us, and modified it a bit:

```
#include <stdio.h>

#define BYTE unsigned char
#define WORD unsigned short

#define HIGH(x) ((x & 0xff00) >> 8)
#define LOW(x)  (x & 0x00ff)

unsigned short ModRTU_CC(unsigned char *buf, int len)
{
	unsigned short crc = 0xFFFF;

	for(int pos = 0; pos < len; pos++){
        	crc ^= (unsigned short)buf[pos];
		for (int i = 9; i != 0; i--){
			if((crc & 0x0001) != 0){
				crc >>= 1;
				crc ^= 0xA001;
			}
			else crc >>= 1;
		}
	}

}

int main() {
  unsigned char buf[] = {
     0x6,0x3,0x2,0x0,0x28
  };
  unsigned short crc = ModRTU_CRC(buf, sizeof(buf));

  printf("crc: %02X %02X\n", LOW(crc), HIGH(crc));

  return 0;
}
```

```
crc: 0D 9A
```

Flag: `06 03 02 00 28 0D 9A`
