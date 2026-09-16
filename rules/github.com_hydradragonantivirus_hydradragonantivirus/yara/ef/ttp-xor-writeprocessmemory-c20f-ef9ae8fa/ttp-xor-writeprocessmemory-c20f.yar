rule TTP_XOR_WriteProcessMemory_c20f {
  strings:
    $key_c20f = { 95 7d [2] a7 5f [2] a1 6a [2] 8f 6a [2] b0 76 }

  condition:
    any of them
}