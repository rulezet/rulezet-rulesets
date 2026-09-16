rule TTP_XOR_WriteProcessMemory_fbcf {
  strings:
    $key_fbcf = { ac bd [2] 9e 9f [2] 98 aa [2] b6 aa [2] 89 b6 }

  condition:
    any of them
}