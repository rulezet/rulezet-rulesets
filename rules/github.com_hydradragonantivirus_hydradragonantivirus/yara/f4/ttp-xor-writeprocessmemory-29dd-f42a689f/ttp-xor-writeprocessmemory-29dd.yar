rule TTP_XOR_WriteProcessMemory_29dd {
  strings:
    $key_29dd = { 7e af [2] 4c 8d [2] 4a b8 [2] 64 b8 [2] 5b a4 }

  condition:
    any of them
}