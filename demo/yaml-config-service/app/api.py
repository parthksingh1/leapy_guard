from flask import Blueprint, jsonify, request

from .config_loader import ConfigError, load_config, load_many
from .defaults import apply_defaults

bp = Blueprint("jobs", __name__)
QUEUE: list[dict] = []


@bp.post("/jobs")
def submit_job():
    try:
        job = apply_defaults(load_config(request.get_data(as_text=True)))
    except ConfigError as exc:
        return jsonify(error=str(exc)), 400
    QUEUE.append(job)
    return jsonify(queued=job["name"], position=len(QUEUE)), 201


@bp.post("/jobs/batch")
def submit_batch():
    try:
        jobs = [apply_defaults(j) for j in load_many(request.get_data(as_text=True))]
    except ConfigError as exc:
        return jsonify(error=str(exc)), 400
    QUEUE.extend(jobs)
    return jsonify(queued=[j["name"] for j in jobs]), 201
