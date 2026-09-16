rule TTP_XOR_WriteProcessMemory_c6db {
  strings:
    $key_c6db = { 91 a9 [2] a3 8b [2] a5 be [2] 8b be [2] b4 a2 }

  condition:
    any of them
}