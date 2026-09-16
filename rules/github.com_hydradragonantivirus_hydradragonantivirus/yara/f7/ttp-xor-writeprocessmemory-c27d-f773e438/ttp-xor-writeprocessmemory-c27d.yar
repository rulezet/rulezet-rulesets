rule TTP_XOR_WriteProcessMemory_c27d {
  strings:
    $key_c27d = { 95 0f [2] a7 2d [2] a1 18 [2] 8f 18 [2] b0 04 }

  condition:
    any of them
}