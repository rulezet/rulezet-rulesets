rule gif_animated: GIF {
  meta:
    author = "Joan Bono"

  strings:
    $a = "GIF89a"

  condition:
    $a at 0
}