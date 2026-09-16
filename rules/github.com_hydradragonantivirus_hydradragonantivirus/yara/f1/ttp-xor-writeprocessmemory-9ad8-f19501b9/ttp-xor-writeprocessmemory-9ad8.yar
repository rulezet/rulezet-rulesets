rule TTP_XOR_WriteProcessMemory_9ad8 {
  strings:
    $key_9ad8 = { cd aa [2] ff 88 [2] f9 bd [2] d7 bd [2] e8 a1 }

  condition:
    any of them
}