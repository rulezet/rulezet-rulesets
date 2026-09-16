import "pe"
rule APT_Lazarus_Stealer_Packed_July_2020_1 {
   meta:
      description = "Detected Lazarus Strealer Packed by Thermida - July 2020"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/DeadlyLynn/status/1286233135751995397"
      date = "2020-07-23"
      hash1 = "431e6784ef33f2b3963464458e73915875947b11348533544cc16c53af64740f"
      hash2 = "70f45a7bbddda140695b953254650486733d8039c63e4eaeb454c1189a97989b"
   strings:
      $s1 = "fill_win32_filefunc64" fullword ascii 
      $s2 = "gzfread" fullword ascii
      $s3 = "deflateGetDictionary" fullword ascii
      $s4 = "gzfwrite" fullword ascii
      $s5 = "adler32_z" fullword ascii
      $s6 = "@AJ<LxwBMDNCIFE}#SRV" fullword ascii
      $s7 = "uncompress2" fullword ascii
      $s8 = "zxyakauj" fullword ascii
      $s9 = "gzfwrite" fullword ascii
      $s10 = "tphfpzvy" fullword ascii
      $s11 = "Dn.dll" fullword ascii
      $s12 = ":USER32.8dl" fullword ascii
      $s13 = "zlib data compression and ZIP file I/O library" fullword wide 
      $s14 = "Dn64.dll" fullword ascii
      $s15 = "zlibwapi.dll" fullword ascii 
      $s16 = "CTRL+_" fullword ascii 
      $s17 = "ZLib.DLL" fullword ascii 
      $s18 = "(C) 1995-2017 Jean-loup Gailly & Mark Adler-" fullword ascii 
      $s19 = "zlib data compression and ZIP file I/O library" fullword ascii 
      $s20 = "DLL support by Alessandro Iacopetti & Gilles Vollant" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 550KB and pe.imphash() == "baa93d47220682c04d92f7797d9224ce" and pe.exports("BZ2_bzInit") and pe.exports("BZ2_bzZip") and pe.exports("BZ2_bzZipW") and pe.exports("adler32_z") and pe.exports("crc32_z") and pe.exports("deflateGetDictionary") and 15 of them}