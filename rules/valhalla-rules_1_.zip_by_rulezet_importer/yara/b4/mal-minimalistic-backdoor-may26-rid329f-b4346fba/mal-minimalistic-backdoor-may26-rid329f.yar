rule MAL_Minimalistic_Backdoor_May26_RID329F : DEMO EXE FILE MAL {
   meta:
      description = "Detects minimalistic backdoor deployment where a shellcode loader downloads an encrypted payload and executes it in memory after RC4 decryption using a command-line provided key"
      author = "MalGamy"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      date = "2026-05-05 14:13:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Note: if multiple processes load the DLL," wide
      $x2 = "Inject (shellcode file is RC4 ciphertext; key is a UTF-8 string" wide
      $s1 = "Error: VirtualAllocEx failed, Win" wide
      $s2 = "Try running as administrator; " wide
      $s3 = ", shellcode size: " wide
      $s4 = "input file path cannot be empty." wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and ( 1 of ( $x* ) or all of ( $s* ) )
}