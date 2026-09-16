rule TTP_XOR_WriteProcessMemory_f51d {
  strings:
    $key_f51d = { a2 6f [2] 90 4d [2] 96 78 [2] b8 78 [2] 87 64 }

  condition:
    any of them
}