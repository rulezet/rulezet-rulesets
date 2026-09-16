rule HackingTeam_Android : Android Implant
{
	meta:
		description = "HackingTeam Android implant, known to detect version v4 - v7"
		author = "Tim 'diff' Strazzere <strazz@gmail.com>"
                reference = "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/"
		date = "2016-11-14"
		version = "1.0"
        strings:
        $decryptor = {  12 01                                       D8 00 ?? ??                                 6E 10 ?? ?? ?? 00                           0C 04                                       21 45                                       01 02                                       01 10                                       32 50 11 00                                 49 03 04 00                                 DD 06 02 5F                                 B7 36                                       D8 03 02 ??                                 D8 02 00 01                                 8E 66                                       50 06 04 00                                 01 20                                       01 32                                       28 F0                                       71 30 ?? ?? 14 05                           0C 00                                       6E 10 ?? ?? 00 00                           0C 00                                       11 00                                    }
                        $settings = {
                        00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E
                        64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74
                        74 69 6E 67 73 3B 00
                    }
                $getSmsInputNumbers = {
                                00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D
                                62 65 72 73 00
                              }
      condition:
        $decryptor and ($settings and $getSmsInputNumbers)
}