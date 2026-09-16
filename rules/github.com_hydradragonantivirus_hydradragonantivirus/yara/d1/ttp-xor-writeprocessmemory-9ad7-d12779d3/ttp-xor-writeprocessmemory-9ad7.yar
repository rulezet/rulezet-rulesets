rule TTP_XOR_WriteProcessMemory_9ad7 {
  strings:
    $key_9ad7 = { cd a5 [2] ff 87 [2] f9 b2 [2] d7 b2 [2] e8 ae }

  condition:
    any of them
}