rule Loader_Buer_Nov_2020_1 {
   meta:
      description = "Detect Buer loader"
      author = "Arkbird_SOLG"
      reference1 = "https://twitter.com/ffforward/status/1333703755439742977"
      reference2 = "https://twitter.com/VK_Intel/status/1333647007920033793"
      reference3 = "https://twitter.com/James_inthe_box/status/1333551419735953409"
      date = "2020-12-01"
      hash1 = "2824d4b0e5a502416696b189bd840870a19dfd555b53535f20b0c87c95f4c232"
      hash2 = "a98abbce5e84c4c3b67b7af3f9b4dc9704b5af33b6183fb3c192e26b1e0ca005"
      hash3 = "ae3ac27e8303519cf04a053a424a0939ecc3905a9a62f33bae3a29f069251b1f"
   strings:
      $s1 = "bcdfghklmnpqrstvwxz" fullword ascii
      $s2 = "%02x" fullword wide
      $s3 = "{%s-%d-%d}" fullword wide
      $s4 = "update" fullword wide 
            $s5 = "]otju}y&Ykx|kx&867?5Ykx|kx&867<" fullword ascii
      $s6 = "]otju}y&Ykx|kx&8678&X8" fullword ascii
      $s7 = "]otju}y&\\oyzg5Ykx|kx&857>" fullword ascii
      $s8 = "]otju}y&>47" fullword ascii
      $s9 = "]otju}y&Ykx|kx&8678" fullword ascii
      $s10 = "]otju}y&=" fullword ascii
      $s11 = "Iutzktz3Z" fullword ascii
      $s12 = "g|mnuuq~4jrr" fullword ascii
      $s13 = "RegularModules" fullword ascii
      $s14 = "]otju}y&>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 10KB and 8 of them
}