rule TTP_XOR_WriteProcessMemory_1bed {
  strings:
    $key_1bed = { 4c 9f [2] 7e bd [2] 78 88 [2] 56 88 [2] 69 94 }

  condition:
    any of them
}