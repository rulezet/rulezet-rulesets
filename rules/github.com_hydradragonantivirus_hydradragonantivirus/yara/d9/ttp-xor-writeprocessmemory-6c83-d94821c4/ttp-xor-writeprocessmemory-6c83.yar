rule TTP_XOR_WriteProcessMemory_6c83 {
  strings:
    $key_6c83 = { 3b f1 [2] 09 d3 [2] 0f e6 [2] 21 e6 [2] 1e fa }

  condition:
    any of them
}