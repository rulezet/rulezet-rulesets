rule TTP_XOR_WriteProcessMemory_ca1d {
  strings:
    $key_ca1d = { 9d 6f [2] af 4d [2] a9 78 [2] 87 78 [2] b8 64 }

  condition:
    any of them
}