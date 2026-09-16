rule TTP_XOR_WriteProcessMemory_1eed {
  strings:
    $key_1eed = { 49 9f [2] 7b bd [2] 7d 88 [2] 53 88 [2] 6c 94 }

  condition:
    any of them
}