rule TTP_XOR_WriteProcessMemory_3c83 {
  strings:
    $key_3c83 = { 6b f1 [2] 59 d3 [2] 5f e6 [2] 71 e6 [2] 4e fa }

  condition:
    any of them
}