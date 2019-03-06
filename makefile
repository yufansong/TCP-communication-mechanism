dirs := $(shell find . -maxdepth 1 -type d)
dirs := $(basename $(patsubst ./%,%,$(dirs)))

.PHONY: $(dirs) clean
$(dirs):
	@for dir in $(dirs); do\
		$(MAKE) -C $$dir;\
	done
clean:
	@for dir in $(dirs); do\
		$(MAKE) -C $$dir clean; \
	done
