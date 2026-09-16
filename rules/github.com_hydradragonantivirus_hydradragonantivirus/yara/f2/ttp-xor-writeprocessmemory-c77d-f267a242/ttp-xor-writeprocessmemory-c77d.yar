rule TTP_XOR_WriteProcessMemory_c77d {
  strings:
    $key_c77d = { 90 0f [2] a2 2d [2] a4 18 [2] 8a 18 [2] b5 04 }

  condition:
    any of them
}