rule TTP_XOR_WriteProcessMemory_113f {
  strings:
    $key_113f = { 46 4d [2] 74 6f [2] 72 5a [2] 5c 5a [2] 63 46 }

  condition:
    any of them
}