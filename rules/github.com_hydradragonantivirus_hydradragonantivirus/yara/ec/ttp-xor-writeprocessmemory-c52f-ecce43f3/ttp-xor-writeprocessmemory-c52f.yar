rule TTP_XOR_WriteProcessMemory_c52f {
  strings:
    $key_c52f = { 92 5d [2] a0 7f [2] a6 4a [2] 88 4a [2] b7 56 }

  condition:
    any of them
}