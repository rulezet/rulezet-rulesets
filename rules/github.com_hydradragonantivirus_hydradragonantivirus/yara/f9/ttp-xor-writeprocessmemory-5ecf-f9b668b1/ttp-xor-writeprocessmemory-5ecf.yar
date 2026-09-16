rule TTP_XOR_WriteProcessMemory_5ecf {
  strings:
    $key_5ecf = { 09 bd [2] 3b 9f [2] 3d aa [2] 13 aa [2] 2c b6 }

  condition:
    any of them
}