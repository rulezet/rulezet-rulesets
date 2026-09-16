rule TTP_XOR_WriteProcessMemory_c47a {
  strings:
    $key_c47a = { 93 08 [2] a1 2a [2] a7 1f [2] 89 1f [2] b6 03 }

  condition:
    any of them
}