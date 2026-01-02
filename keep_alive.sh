#!/bin/bash
# SW4RD CHEAT BOT Keep-Alive Script

BOT_DIR="/home/ubuntu/DAJAL_NEW/DAJAL"
VENV_PATH="$BOT_DIR/venv/bin/activate"
LOG_FILE="$BOT_DIR/bot.log"

cd $BOT_DIR

while true; do
    echo "$(date): Starting SW4RD CHEAT Bot..." >> $LOG_FILE
    source $VENV_PATH
    python3 main.py >> $LOG_FILE 2>&1
    echo "$(date): Bot crashed or stopped. Restarting in 5 seconds..." >> $LOG_FILE
    sleep 5
done
