rule TTP_XOR_WriteProcessMemory_d11d {
  strings:
    $key_d11d = { 86 6f [2] b4 4d [2] b2 78 [2] 9c 78 [2] a3 64 }

  condition:
    any of them
}