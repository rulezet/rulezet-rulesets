rule TTP_XOR_WriteProcessMemory_d12d {
  strings:
    $key_d12d = { 86 5f [2] b4 7d [2] b2 48 [2] 9c 48 [2] a3 54 }

  condition:
    any of them
}