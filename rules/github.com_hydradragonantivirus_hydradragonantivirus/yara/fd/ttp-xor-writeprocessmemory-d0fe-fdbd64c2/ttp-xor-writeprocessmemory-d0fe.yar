rule TTP_XOR_WriteProcessMemory_d0fe {
  strings:
    $key_d0fe = { 87 8c [2] b5 ae [2] b3 9b [2] 9d 9b [2] a2 87 }

  condition:
    any of them
}