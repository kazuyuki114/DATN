#!/bin/bash

VICTIM_IP="192.168.56.103" # Thay bằng IP Victim của bạn

# --- CẤU HÌNH THỜI GIAN MÔ PHỎNG ---
# 60 giây đời thực = 1 giờ trong mạng ảo. 
# (Muốn chạy thời gian thực thì đổi thành 3600)
REAL_SECS_PER_SIM_HOUR=3600 
TOTAL_DAYS=7 # Chạy mô phỏng trong 1 tuần

echo "Khởi động Hệ thống Sinh Lưu lượng Nâng cao (Mô phỏng $TOTAL_DAYS ngày)..."

# Hàm sinh lưu lượng trong 1 khung giờ
generate_traffic_for_hour() {
    local DAY=$1
    local HOUR=$2
    local END_TIME=$(($(date +%s) + REAL_SECS_PER_SIM_HOUR))

    # 1. THIẾT LẬP CHU KỲ TRONG NGÀY (Gradual Increase/Decrease)
    # Tính theo % (100 = mức trung bình, 200 = gấp đôi, 20 = rất ít)
    if [ $HOUR -ge 0 ] && [ $HOUR -lt 6 ]; then
        # Đêm khuya: Ít người dùng
        WEB_PCT=20; FILE_PCT=10; VID_PCT=20
    elif [ $HOUR -ge 6 ] && [ $HOUR -lt 9 ]; then
        # Sáng sớm: Bắt đầu đi làm, tăng dần
        WEB_PCT=80; FILE_PCT=50; VID_PCT=40
    elif [ $HOUR -ge 9 ] && [ $HOUR -lt 12 ]; then
        # Sáng làm việc: Web nhiều, Tải file nhiều
        WEB_PCT=150; FILE_PCT=180; VID_PCT=20
    elif [ $HOUR -ge 12 ] && [ $HOUR -lt 14 ]; then
        # Giờ nghỉ trưa: Xem video tăng, lướt web tăng mạnh
        WEB_PCT=200; FILE_PCT=30; VID_PCT=150
    elif [ $HOUR -ge 14 ] && [ $HOUR -lt 17 ]; then
        # Chiều làm việc
        WEB_PCT=150; FILE_PCT=200; VID_PCT=30
    elif [ $HOUR -ge 17 ] && [ $HOUR -lt 20 ]; then
        # Chiều tối: Tan làm, chuẩn bị nghỉ ngơi
        WEB_PCT=100; FILE_PCT=50; VID_PCT=100
    else
        # Tối (20-23): Giải trí, stream video cực mạnh
        WEB_PCT=80; FILE_PCT=20; VID_PCT=250
    fi

    # 2. THIẾT LẬP TÍNH MÙA VỤ (Seasonal Variation: Cuối tuần vs Ngày thường)
    if [ $DAY -eq 6 ] || [ $DAY -eq 7 ]; then
        # Cuối tuần: Ít làm việc (Web/File giảm), Giải trí nhiều (Video tăng)
        WEB_PCT=$((WEB_PCT * 50 / 100))
        FILE_PCT=$((FILE_PCT * 10 / 100))
        VID_PCT=$((VID_PCT * 150 / 100))
    fi

    # 3. MÔ PHỎNG ĐỘT BIẾN NGẪU NHIÊN (Sudden Spike)
    # Mỗi giờ có 5% cơ hội xảy ra một lượng truy cập tăng vọt (VD: Sự kiện hot)
    SPIKE_ACTIVE=0
    if [ $((RANDOM % 100)) -lt 5 ]; then
        echo "  [!] PHÁT HIỆN ĐỘT BIẾN LƯU LƯỢNG (Sudden Spike) vào Giờ $HOUR!"
        WEB_PCT=$((WEB_PCT * 4)) # Gấp 4 lần bình thường
        SPIKE_ACTIVE=1
    fi

    # 4. MÔ PHỎNG MẪU ĐỊNH KỲ (Periodic Pattern Change)
    # Hàng ngày cứ đúng 2h sáng (Giờ mô phỏng) là chạy Backup Database
    if [ $HOUR -eq 2 ]; then
        echo "  [*] Chạy tiến trình Backup định kỳ (2:00 AM)..."
        # Bắn 1 luồng TCP iperf3 cực mạnh trong vài giây
        iperf3 -c $VICTIM_IP -p 5001 -t 5 -b 100M > /dev/null 2>&1 &
    fi

    echo "Ngày $DAY | Giờ: $HOUR:00 | Cường độ: Web ${WEB_PCT}% - File ${FILE_PCT}% - Video ${VID_PCT}%"

    # VÒNG LẶP CHẠY LƯU LƯỢNG TRONG KHUNG GIỜ NÀY
    while [ $(date +%s) -lt $END_TIME ]; do
        
        # --- LƯỚT WEB (TCP 80) ---
        USERS=$(( 10 * WEB_PCT / 100 ))
        [ $USERS -lt 1 ] && USERS=1 # Đảm bảo tối thiểu 1 user
        REQUESTS=$(( USERS * 5 ))
        ab -n $REQUESTS -c $USERS http://$VICTIM_IP/ > /dev/null 2>&1 &
        
        # --- TẢI FILE (TCP 5001) ---
        FILE_BW=$(( 10 * FILE_PCT / 100 ))
        if [ $FILE_BW -gt 0 ]; then
            iperf3 -c $VICTIM_IP -p 5001 -t 2 -b ${FILE_BW}M > /dev/null 2>&1 &
        fi
        
        # --- XEM VIDEO (UDP 5002) ---
        VID_BW=$(( 5 * VID_PCT / 100 ))
        if [ $VID_BW -gt 0 ]; then
            iperf3 -c $VICTIM_IP -p 5002 -u -t 3 -b ${VID_BW}M > /dev/null 2>&1 &
        fi

        # --- ICMP PING NỀN ---
        ping -c 1 $VICTIM_IP > /dev/null 2>&1 &

        # Nghỉ ngẫu nhiên 1-3 giây giữa các nhịp request để tránh treo máy Client
        sleep $((1 + RANDOM % 3))
    done
}

# --- CHƯƠNG TRÌNH CHÍNH ---
for DAY in $(seq 1 $TOTAL_DAYS); do
    for HOUR in {0..23}; do
        generate_traffic_for_hour $DAY $HOUR
    done
    echo "=== HOÀN THÀNH NGÀY MÔ PHỎNG THỨ $DAY ==="
done

echo "Hoàn tất sinh dữ liệu Normal Traffic!"


