import "pe"
rule case_26364_cobalt_strike_smb_beacon {
   meta:
      description = "Case 26364 - file e225857.exe Cobalt Strike SMB beacon"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "f474241a5d082500be84a62f013bc2ac5cde7f18b50bf9bb127e52bf282fffbf"
   strings:
      $s1 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
      $s2 = "IplPi\\lHiX" fullword ascii
      $s3 = "!IToX|\\M\\8\\" fullword ascii
      $s4 = "lXixf`ix" fullword ascii
      $s5 = "lXitnXix" fullword ascii
      $s6 = "MTnHiD$" fullword ascii
      $s7 = "mXGPnXiP$" fullword ascii
      $s8 = "DlPi,lHi$" fullword ascii
      $s9 = "nHilf!" fullword ascii
      $s10 = "hHit\"Xit" fullword ascii
      $s11 = "hPitlXi" fullword ascii
      $s12 = "/I^lXiPnXiP$" fullword ascii
      $s13 = "MTnHi|$" fullword ascii
      $s14 = "nXiDf$U)" fullword ascii
      $s15 = "IUlXi|nXi|$" fullword ascii
      $s16 = "nHixnhiHn`it" fullword ascii
      $s17 = "MTnHiH$" fullword ascii
      $s18 = "lPitlXi|" fullword ascii
      $s19 = "XeYv ,8?[" fullword ascii
      $s20 = "lXitf`it" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      ( pe.imphash() == "bed5688a4a2b5ea6984115b458755e90" or pe.imphash() == "1b2b0fc8f126084d18c48b4f458c798b" or 8 of them )
}