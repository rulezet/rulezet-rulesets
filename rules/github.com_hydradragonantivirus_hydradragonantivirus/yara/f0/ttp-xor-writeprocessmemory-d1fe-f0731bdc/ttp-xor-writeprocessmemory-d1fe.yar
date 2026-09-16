rule TTP_XOR_WriteProcessMemory_d1fe {
  strings:
    $key_d1fe = { 86 8c [2] b4 ae [2] b2 9b [2] 9c 9b [2] a3 87 }

  condition:
    any of them
}