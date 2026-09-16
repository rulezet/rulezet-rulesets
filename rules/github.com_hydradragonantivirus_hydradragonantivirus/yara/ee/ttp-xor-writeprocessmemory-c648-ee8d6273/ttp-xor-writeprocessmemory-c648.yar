rule TTP_XOR_WriteProcessMemory_c648 {
  strings:
    $key_c648 = { 91 3a [2] a3 18 [2] a5 2d [2] 8b 2d [2] b4 31 }

  condition:
    any of them
}