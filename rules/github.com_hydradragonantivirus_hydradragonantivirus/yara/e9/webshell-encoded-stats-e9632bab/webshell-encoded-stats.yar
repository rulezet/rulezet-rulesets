import "math"
rule webshell_encoded_stats: WEBSHELL PROD {
  meta:
    description = "Webshell having statistical signs of encoded code which gets dynamically executed"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/02/07"

  condition:
        filesize > 2KB and
    (
                  math.entropy(500, filesize - 500) >= 5.7 and
            math.mean(500, filesize - 500) > 80 and
                        math.deviation(500, filesize - 500, 89.0) < 23
    ) or (
                  math.entropy(500, filesize - 500) >= 7.7 and
            math.mean(500, filesize - 500) > 120 and
      math.mean(500, filesize - 500) < 136 and
                        math.deviation(500, filesize - 500, 89.0) > 65
    )
}