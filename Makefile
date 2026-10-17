.PHONY: release-drover release-drover-dry-run

# Build herdr-drover for this platform and publish it to Agent Hub. Needs ZIG (Zig 0.16).
release-drover:
	bash scripts/release-drover.sh

release-drover-dry-run:
	bash scripts/release-drover.sh --dry-run
