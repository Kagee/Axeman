#! /bin/bash
curl -s https://crt.sh/monitored-logs | grep -P -i '<td>https' | sed -e 's#^\s*<TD>https://##' -e 's#</TD>##' | sort | uniq | sed -e 's#/#\.#g' -e 's/[^a-z0-9\.]*//g' | xargs -L 1 -I {} bash -c '[[ -d "./output/{}" ]] || echo "Missing: {}"'
