```C
/*  
 *  __________ ____ _____________  ___________________  
 *  \______   \    |   \______   \/  _____/\_   _____/  
 *   |     ___/    |   /|       _/   \  ___ |    __)_  
 *   |    |   |    |  / |    |   \    \_\  \|        \  
 *   |____|   |______/  |____|_  /\______  /_______  /  
 *                            \/        \/        \/  
 *  
 * Designed by kojiba.  
 *  
 */  
  
```

Purge - 512 bit, 30 rounds symmetric encryption algorithm, designed for x64 bit archs.

Free and opensource.  
Free from NSA, goverments and other shit.  
Just only an cleaning instrument.  
Easy for customise, recompile, use for custom cipher systems.  
  
Here is a round some  

![Purge round](https://github.com/kojiba/purge/blob/master/purge%20round.png)

Data samples  
```C
Data:
  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  
Key:  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  

Ciphered:  
B8 FF E8 11 EB 46 0F FE 12 AE 7F 34 E7 7A 03 49 18 B8 F8 AA EA F4 D6 3D 1F A8 98 35 35 C7 5C 42  
91 42 7E 4C CF EA E4 30 56 6E 4B 28 19 4D D0 FA 72 55 FE DB 48 D5 79 FA 5A 1D 9B 47 10 9D E1 7E  
```

Use PurgeEvasionUtils.h to perform cryptography operations like enc/dec/hash.
See https://github.com/kojiba/RayLanguage for better security integrations.

11/23/2015 Ukraine Kharkiv