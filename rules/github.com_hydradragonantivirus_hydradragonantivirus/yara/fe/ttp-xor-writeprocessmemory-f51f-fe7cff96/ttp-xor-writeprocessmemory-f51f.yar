rule TTP_XOR_WriteProcessMemory_f51f {
  strings:
    $key_f51f = { a2 6d [2] 90 4f [2] 96 7a [2] b8 7a [2] 87 66 }

  condition:
    any of them
}