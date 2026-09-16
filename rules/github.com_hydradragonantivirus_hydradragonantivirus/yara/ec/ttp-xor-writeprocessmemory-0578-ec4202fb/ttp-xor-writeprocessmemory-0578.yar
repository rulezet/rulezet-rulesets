rule TTP_XOR_WriteProcessMemory_0578 {
  strings:
    $key_0578 = { 52 0a [2] 60 28 [2] 66 1d [2] 48 1d [2] 77 01 }

  condition:
    any of them
}