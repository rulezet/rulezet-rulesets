rule power_pe_injection
{
   meta:
      description      = "PowerShell with PE Reflective Injection"
      author         = "Benjamin DELPY (gentilkiwi)"
      id = "a71fe9f2-9c2a-5650-a5c7-116b76f10db6"
   strings:
      $str_loadlib   = "0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9"
   condition:
      $str_loadlib
}