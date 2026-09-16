rule TTP_XOR_WriteProcessMemory_f578 {
  strings:
    $key_f578 = { a2 0a [2] 90 28 [2] 96 1d [2] b8 1d [2] 87 01 }

  condition:
    any of them
}