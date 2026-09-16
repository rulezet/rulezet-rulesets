rule MAL_Minimalistic_Backdoor_May26 {
   meta:
      description = "Detects minimalistic backdoor deployment where a shellcode loader downloads an encrypted payload and executes it in memory after RC4 decryption using a command-line provided key"
      author = "MalGamy"
      date = "2026-05-05"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      hash = "395ec7acd475a8acd358adc75c4615cf41737aed8a96c4f2dd792c8a6af4140c"
      score = 80
      id = "8292161d-8b20-51e0-987a-dd0f4c1cf3e8"
   strings:
      $x1 = "Note: if multiple processes load the DLL," wide
      $x2 = "Inject (shellcode file is RC4 ciphertext; key is a UTF-8 string" wide

      $s1 = "Error: VirtualAllocEx failed, Win" wide
      $s2 = "Try running as administrator; " wide
      $s3 = ", shellcode size: " wide
      $s4 = "input file path cannot be empty." wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 50KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
}