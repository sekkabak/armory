#/bin/bash

git clone https://github.com/samoshkin/tmux-config.git /tmp/tmux-conf
/tmp/tmux-conf/install.sh
rm -rf /tmp/tmux-conf
curl -s https://gist.githubusercontent.com/sekkabak/a1b8c6b00b3314658beb86c111370d37/raw/ec9e820e4c219be01dd8551a9a22819ab6d88be4/.tmux.conf > ~/.tmux.conf
