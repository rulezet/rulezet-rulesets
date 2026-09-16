rule TTP_XOR_WriteProcessMemory_d61d {
  strings:
    $key_d61d = { 81 6f [2] b3 4d [2] b5 78 [2] 9b 78 [2] a4 64 }

  condition:
    any of them
}