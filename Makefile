SRC = mindpq.py
TEST = test.py

venv: requirements.txt requirements_dev.txt
	@python3 -m venv $@
	@source $@/bin/activate && pip install -r $< -r requirements_dev.txt
	@echo "enter virtual environment: source $@/bin/activate"

tags: $(SRC) $(TEST)
	@ctags --languages=python --python-kinds=-i $(SRC) $(TEST)

.PHONY: test
test:
	@python -m unittest

coverage: $(SRC) $(TEST)
	@coverage run --source=. --branch --concurrency=thread $(TEST)
	@coverage report -m
	@coverage html -d ./coverage
	@coverage erase

.PHONY: lint
lint:
	@pylint -f colorized $(SRC) $(TEST)

.PHONY: typecheck
typecheck:
	@mypy $(SRC) $(TEST)

.PHONY: clean
clean:
	@$(RM) -r coverage
	@$(RM) -r .mypy_cache
	@$(RM) -r __pycache__
	@$(RM) tags
