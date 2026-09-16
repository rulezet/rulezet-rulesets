rule TTP_XOR_WriteProcessMemory_01fe {
  strings:
    $key_01fe = { 56 8c [2] 64 ae [2] 62 9b [2] 4c 9b [2] 73 87 }

  condition:
    any of them
}