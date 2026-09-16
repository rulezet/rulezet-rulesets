rule TTP_XOR_WriteProcessMemory_c27a {
  strings:
    $key_c27a = { 95 08 [2] a7 2a [2] a1 1f [2] 8f 1f [2] b0 03 }

  condition:
    any of them
}