rule TTP_XOR_WriteProcessMemory_6fdc {
  strings:
    $key_6fdc = { 38 ae [2] 0a 8c [2] 0c b9 [2] 22 b9 [2] 1d a5 }

  condition:
    any of them
}