rule TTP_XOR_WriteProcessMemory_9a83 {
  strings:
    $key_9a83 = { cd f1 [2] ff d3 [2] f9 e6 [2] d7 e6 [2] e8 fa }

  condition:
    any of them
}