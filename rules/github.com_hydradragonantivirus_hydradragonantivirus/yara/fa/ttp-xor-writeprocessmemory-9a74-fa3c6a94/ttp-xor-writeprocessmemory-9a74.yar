rule TTP_XOR_WriteProcessMemory_9a74 {
  strings:
    $key_9a74 = { cd 06 [2] ff 24 [2] f9 11 [2] d7 11 [2] e8 0d }

  condition:
    any of them
}