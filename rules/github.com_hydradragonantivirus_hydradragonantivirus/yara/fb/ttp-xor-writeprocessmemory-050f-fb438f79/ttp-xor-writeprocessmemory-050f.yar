rule TTP_XOR_WriteProcessMemory_050f {
  strings:
    $key_050f = { 52 7d [2] 60 5f [2] 66 6a [2] 48 6a [2] 77 76 }

  condition:
    any of them
}